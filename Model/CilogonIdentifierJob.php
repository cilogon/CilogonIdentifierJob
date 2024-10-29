<?php

App::uses("CoJobBackend", "Model");
App::uses("CoHttpClient", "Lib");

class CilogonIdentifierJob extends CoJobBackend {
  // Required by COmanage Plugins
  public $cmPluginType = "job";

  // Document foreign keys
  public $cmPluginHasMany = array();

  // Validation rules for table elements
  public $validate = array();

  // Current CO Job Object
  private $CoJob;

  // Current CO ID
  private $coId;

  private $entityID = null;

  // Instance of CoHttpClient for OA4MP dbService
  private $Http = null;

  // Flag for XML parser.
  private $recordNow = false;

  // State variable for XML parser holding parsed entityID scope.
  private $scope = null;

  // Mapping from scope to IdP entityID.
  private $scopeToIdp = array();

  /**
   * Process data element for XML parser.
   *
   * @since COmanage Registry 4.3.5
   * @return void
   */

  protected function charData($parser, $data) {
    // If signalled we are parsing the shibmd:Scope element
    // then record the element data as the scope.
    if($this->recordNow) {
      $this->scope = $data;
    }
  }

  /**
   * Create HTTP client connected to OA4MP
   *
   * @since COmanage Registry 4.3.5
   * @return void
   */

  protected function createHttpClient() {
    $this->Http = new CoHttpClient();

    $config = array();
    $config['serverurl'] = 'http://oa4mp-server.cilogon-service.svc.cluster.local:8888/oauth2/dbService';
    $config['auth_type'] = HttpServerAuthType::None;
    $config['ssl_verify_host'] = false;
    $config['ssl_verify_peer'] = false;

    $this->Http->setConfig($config);
  }

  /**
   * Process the start of an element for XML parser.
   *
   * @since COmanage Registry 4.3.5
   * @return void
   */

  protected function elementStart($parser, $elementName, $attrs) {
    // If passed the EntityDescriptor element pick off the entityID
    // attribute value and record it.
    if(preg_match('/EntityDescriptor/i', $elementName)) {
      foreach($attrs as $key => $value) {
        if(preg_match('/entityID/i', $key)) {
          $this->entityID = $value;
        }
      }
    } elseif(preg_match('/shibmd:Scope/i', $elementName)) {
      // If passed the scope element forget any previous scope
      // value and signal to record the element data.
      $this->scope = null;
      $this->recordNow = true;
    }
  }

  /**
   * Process the end of an element for XML parser.
   *
   * @since COmanage Registry 4.3.5
   * @return void
   */

  protected function elementEnd($parser, $elementName) {
    if(preg_match('/EntityDescriptor/i', $elementName)) {
      // At the end of the EntityDescriptor element forget the
      // previous value for entityID.
      $this->entityID = null;
    } elseif(preg_match('/shibmd:Scope/i', $elementName)) {
      // At the end of the scope element update the mapping
      // from scope to entityID and signal to stop saving
      // data.
      $this->scopeToIdp[$this->scope] = $this->entityID;
      $this->recordNow = false;
    }
  }

  /**
   * Execute the requested Job.
   *
   * @param  int   $coId    CO ID
   * @param  CoJob $CoJob   CO Job Object, id available at $CoJob->id
   * @param  array $params  Array of parameters, as requested via parameterFormat()
   * @throws InvalidArgumentException
   * @throws RuntimeException
   * @return void
   */
  public function execute($coId, $CoJob, $params) {
    $CoJob->update($CoJob->id, null, "full", null);

    $this->CoJob = $CoJob;
    $this->coId = $coId;

    // Parse the SAML metadata aggregate XML file.
    $metadataPath = $params['metadata'];
    if(!$this->parseMetadata($metadataPath)) {
      $summary = "Failed to parse SAML metadata";
      $status = JobStatusEnum::Failed;

      $CoJob->finish($CoJob->id, $summary, $status);
      return;
    }

    // Create the connection to OA4MP.
    $this->createHttpClient();

    $requestedOrgId = $params['orgid'] ?? null;

    if(!empty($requestedOrgId)) {
      $result = $this->processOneOrgId($requestedOrgId);
    } else {
      $result = $this->processAllOrgIds();
    }

    $added = $result['added'];
    $failed = $result['failed'];
    $status = $result['status'];

    $summary = "Successfully added $added CILogon identifiers and recorded $failed failures";

    $CoJob->finish($CoJob->id, $summary, $status);
  }

  /**
   * @since  COmanage Registry v4.3.5
   * @return Array Array of supported parameters.
   */

  public function getAvailableJobs() {
    $availableJobs = array();

    $availableJobs['CilogonIdentifier'] = "Add CILogon Identifier as OIDC sub Identifier to Org IDs";

    return $availableJobs;
  }

  /**
   * Obtain the list of parameters supported by this Job.
   *
   * @since  COmanage Registry v4.3.5
   * @return Array Array of supported parameters.
   */
  public function parameterFormat() {
    $params = array(
      'metadata' => array(
        'help' => _txt('pl.cilogonidentifierjob.job.identifier.metadata'),
        'type' => 'string',
        'required' => true
      ),
      'orgid' => array(
        'help' => _txt('pl.cilogonidentifierjob.job.identifier.orgid'),
        'type' => 'int',
        'required' => false
      )
    );

    return $params;
  }

  /**
   * Invoke the OA4MP dbServic getUser endpoint or action.
   *
   * @since COmanage Registry v4.3.5
   * @throws RuntimeException for any return code other than 200.
   * @return Array Array of user information.
   */

  protected function getUser($params) {
    $response = $this->Http->post("", $params);
    $code = $response->code;

    if($code != 200) {
      $msg = "dbService response code was " . $code;
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $user = array();
    foreach(explode(PHP_EOL, $response->body) as $line) {
      if(empty($line)) {
        continue;
      }
      list($key, $value) = explode("=", $line);
      $user[$key] = $value;
    }

    return $user;
  }

  /**
   * Parse the InCommon SAML metadata aggregate file.
   *
   * @since COmanage Regisry v4.3.5
   * @param string $path path to the file
   * @return boolean true for success
   */

  protected function parseMetadata($path) {
    $parser = xml_parser_create();

    xml_set_element_handler($parser, array($this, 'elementStart'), array($this, 'elementEnd'));
    xml_set_character_data_handler($parser, array($this, 'charData'));

    $fp = fopen($path, "r");
    if($fp === false) {
      return false;
    }

    while($data = fread($fp, 4096)) {
      xml_parse($parser, $data, feof($fp));
    }

    fclose($fp);
    xml_parser_free($parser);

    return true;
  }

  /**
   * Process all Org IDs.
   *
   * @since COmanage Registry v4.3.5
   * @return Array array indicating status.
   */

  protected function processAllOrgIds() {
    $ret = array();
    $ret['added'] = 0;
    $ret['failed'] = 0;
    $ret['status'] = JobStatusEnum::Failed;

    // Pull all Org IDs and Identifiers.
    $args = array();
    $args['conditions']['OrgIdentity.co_id'] = $this->coId;
    $args['contain'][] = 'Identifier';

    $orgIdentities = $this->CoJob->Co->OrgIdentity->find('all', $args);

    foreach($orgIdentities as $orgIdentity) {
      // Return if this CoJob invocation has been cancelled.
      if($this->CoJob->canceled($this->CoJob->id)) {
        $ret['status'] = JobStatusEnum::Cancelled;

        return $ret;
      }

      // Skip over OrgIdentity that has no Identifiers.
      if(empty($orgIdentity['Identifier'])) {
        continue;
      }

      $orgId = $orgIdentity['OrgIdentity']['id'];
      $result = $this->processOneOrgId($orgId);

      $jobHistoryRecordKey = "orgID=$orgId";
      $jobHistoryComment = $result['comment'];

      switch ($result['status']) {
        case JobStatusEnum::Complete:
          $ret['added'] += $result['added'];
          $this->CoJob->CoJobHistoryRecord->record($this->CoJob->id, $jobHistoryRecordKey, $jobHistoryComment, null, null, JobStatusEnum::Complete);
          break;

        case JobStatusEnum::Failed:
          $ret['failed'] += $result['failed'];
          $this->CoJob->CoJobHistoryRecord->record($this->CoJob->id, $jobHistoryRecordKey, $jobHistoryComment, null, null, JobStatusEnum::Failed);
          break;
      }

    }

    $ret['status'] = JobStatusEnum::Complete;

    return $ret;
  }

  /**
   * Process one Org ID.
   *
   * @since COmanage Registry v4.3.5
   * @param int $orgId the Org ID to process.
   * @return Array array indicating status.
   */

  protected function processOneOrgId($orgId) {
    $ret = array();
    $ret['added'] = 0;
    $ret['failed'] = 0;
    $ret['status'] = JobStatusEnum::Failed;
    $ret['comment'] = "";

    // Pull the Org ID and linked Identifier, Name, EmailAddress,
    // and CoOrgIdentityLink objects.
    $args = array();
    $args['conditions']['OrgIdentity.id'] = $orgId;
    $args['contain'][] = 'Identifier';
    $args['contain'][] = 'Name';
    $args['contain'][] = 'EmailAddress';
    $args['contain'][] = 'CoOrgIdentityLink';

    $orgIdentity = $this->CoJob->Co->OrgIdentity->find('first', $args);

    if(empty($orgIdentity)) {
      $ret['failed'] += 1;
      $ret['comment'] = "Could not find OrgIdentity with id = $orgId";
      return $ret;
    }

    // Verify that the OrgID belongs to the CO.
    if($orgIdentity['OrgIdentity']['co_id'] != $this->coId) {
      $ret['failed'] += 1;
      $ret['comment'] = "OrgIdentity with id = $orgId is not in the CO";
      return $ret;
    }

    // We need at least one Identifier to consider.
    if(empty($orgIdentity['Identifier'])) {
      $ret['failed'] += 1;
      $ret['comment'] = "OrgIdentity with id = $orgId has no Identifiers";
      return $ret;
    }

    // Holds the query parameters used with the OA4MP dbService end point.
    $queryParameters = array();

    // We always use the action getUser.
    $queryParameters['action'] = 'getUser';

    foreach($orgIdentity['Identifier'] as $i) {
      // The Org ID already has a CILogon user identifier linked so signal
      // success and return.
      if($i['type'] == 'oidcsub' && (preg_match('@^http://cilogon.org@', $i['identifier']) === 1)) {
        $ret['status'] = JobStatusEnum::Complete; 
        $ret['comment'] = "OrgIdentity with id = $orgId already has CILogon user identifier";
        return $ret;
      }

      if($i['type'] == 'eppn') {
        $eppn = $i['identifier'];
        // ePPN values with scope cosmicexplorer.org represent an ORCID authentication
        // that used an ORCID to SAML gateway. The left-hand side of the ePPN is the
        // ORCID without the http://orcid.org prefix.
        $special = preg_match('/(.+)@(orcid\.)?cosmicexplorer.org$/', $eppn, $matches);
        if($special === 1) {
          // Register a CILogon ORCID user rather than ePPN.
          $queryParameters['oidc'] = 'http://orcid.org/' . $matches[1];
          $queryParameters['idp'] = 'http://orcid.org/oauth/authorize';
        } else {
          // Register a CILogon user using ePPN.
          $queryParameters['eppn'] = $eppn;
          $scope = explode('@', $eppn)[1];
          $entityID = $this->scopeToIdp[$scope] ?? null;

          // Fail if we cannot map the eppn to an IdP.
          if(empty($entityID)) {
            $ret['failed'] += 1;
            $ret['comment'] = "OrgIdentity with id = $orgId cannot map ePPN $eppn to IdP";
            return $ret;
          }

          $queryParameters['idp'] = $entityID;
        }
      }
    }

    // Use the first email address we find.
    foreach($orgIdentity['EmailAddress'] as $e) {
      if(!empty($e['mail'])) {
        $queryParameters['email'] = $e['mail'];
        break;
      }
    }

    // Use the first name we find. Use a default for an empty
    // given or family name.
    foreach($orgIdentity['Name'] as $n) {
      $queryParameters['first_name'] = empty($n['given']) ? 'Unknownname' : $n['given'];
      $queryParameters['last_name'] = empty($n['family']) ? 'Unknownname' : $n['family'];
      break;
    }

    // Invoke the dbService getUser end point.
    try {
      $cilogonUser = $this->getUser($queryParameters);
    } catch (Exception $e) {
      $ret['failed'] += 1;
      $ret['comment'] = "OrgIdentity with id = $orgId dbService returned error";
      return $ret;
    }

    // Add the new CILogon user identifier as an OIDC sub Identifier
    // to the OrgID.
    $cilogonUserIdentifier = urldecode($cilogonUser['user_uid']);

    $args = array();
    $args['Identifier']['identifier'] = $cilogonUserIdentifier;
    $args['Identifier']['org_identity_id'] = $orgId;
    $args['Identifier']['type'] = IdentifierEnum::OIDCsub;
    $args['Identifier']['login'] = true;
    $args['Identifier']['status'] = SuspendableStatusEnum::Active;

    $this->CoJob->Co->OrgIdentity->Identifier->clear();
    $this->CoJob->Co->OrgIdentity->Identifier->save($args);

    // Add the new CILogon user identifier as an SOR Identifier
    // to the OrgID.
    $args = array();
    $args['Identifier']['identifier'] = $cilogonUserIdentifier;
    $args['Identifier']['org_identity_id'] = $orgId;
    $args['Identifier']['type'] = IdentifierEnum::SORID;
    $args['Identifier']['login'] = false;
    $args['Identifier']['status'] = SuspendableStatusEnum::Active;

    $this->CoJob->Co->OrgIdentity->Identifier->clear();
    $this->CoJob->Co->OrgIdentity->Identifier->save($args);

    if(!empty($orgIdentity['CoOrgIdentityLink'])) {
      $coPersonId = $orgIdentity['CoOrgIdentityLink'][0]['co_person_id'];

      // Add the new CILogon user identifier as an OIDC sub Identifier
      // to the CO Person record.
      $args = array();
      $args['Identifier']['identifier'] = $cilogonUserIdentifier;
      $args['Identifier']['co_person_id'] = $coPersonId;
      $args['Identifier']['type'] = IdentifierEnum::OIDCsub;
      $args['Identifier']['login'] = false;
      $args['Identifier']['status'] = SuspendableStatusEnum::Active;

      $this->CoJob->Co->CoPerson->Identifier->clear();
      $this->CoJob->Co->CoPerson->Identifier->save($args);

      // Add the new CILogon user identifier as an SOR Identifier
      // to the OrgID.
      $args = array();
      $args['Identifier']['identifier'] = $cilogonUserIdentifier;
      $args['Identifier']['co_person_id'] = $coPersonId;
      $args['Identifier']['type'] = IdentifierEnum::SORID;
      $args['Identifier']['login'] = false;
      $args['Identifier']['status'] = SuspendableStatusEnum::Active;

      $this->CoJob->Co->CoPerson->Identifier->clear();
      $this->CoJob->Co->CoPerson->Identifier->save($args);
    }

    $ret['added'] += 1;
    $ret['status'] = JobStatusEnum::Complete;
    $ret['comment'] = "OrgIdentity with id = $orgId added $cilogonUserIdentifier";

    return $ret;
  }
}
