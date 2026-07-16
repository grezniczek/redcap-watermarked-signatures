<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule;

use Exception;

require_once "classes/ActionTagHelper.php";
require_once "classes/InjectionHelper.php";

class WatermarkedSignaturesExternalModule extends \ExternalModules\AbstractExternalModule
{
    private $js_debug = false;

    /** @var \Project */
    private $proj = null;
    private $project_id = null;

    const ACTIONTAG = "@WATERMARKED-SIGNATURE";

    #region Hooks

    function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();
    }

    function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();
    }

    function redcap_every_page_top($project_id)
    {
        // Skip non-project context
        if ($project_id == null) return;

        // Initialize
        $this->init_proj($project_id);
        $this->init_config();
    }

    function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        $this->init_proj($project_id);
        $user = $this->framework->getUser($user_id);
        $rights = $user->getRights($project_id);

        return null;
    }

    #endregion



    #region Private Helpers


    private function init_proj($project_id)
    {
        if ($this->proj == null) {
            $this->proj = new \Project($project_id);
            $this->project_id = $project_id;
        }
    }

    private function require_proj()
    {
        if ($this->proj == null) {
            throw new Exception($this->tt("error_project_not_initialized"));
        }
    }

    private function init_config()
    {
        $this->require_proj();
        $setting = $this->getProjectSetting("javascript-debug");
        $this->js_debug = $setting == true;
    }

    #endregion

}
