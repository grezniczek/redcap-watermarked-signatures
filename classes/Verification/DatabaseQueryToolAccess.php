<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

/**
 * Mirrors REDCap's Control Center Database Query Tool access gate.
 */
class DatabaseQueryToolAccess
{
	/**
	 * @return bool
	 */
	public static function canAccessDatabaseQueryTool()
	{
		$adminRights = defined('ADMIN_RIGHTS') ? (bool) ADMIN_RIGHTS : false;
		$superUser = defined('SUPER_USER') ? (bool) SUPER_USER : false;
		$systemConfiguration = defined('ACCESS_SYSTEM_CONFIG') ? (bool) ACCESS_SYSTEM_CONFIG : false;

		// REDCap denies access when none of these roles is present:
		// !ADMIN_RIGHTS && !SUPER_USER && !ACCESS_SYSTEM_CONFIG.
		return ($adminRights || $superUser || $systemConfiguration)
			&& (string) ($GLOBALS['database_query_tool_enabled'] ?? '') === '1';
	}
}
