# ADD THIS FUNCTION TO menuscript/ui/interactive.py
# Insert it BEFORE the import_data_menu() function (around line 1967)

def test_credentials_menu():
    """Interactive credential testing menu."""
    from menuscript.testing.credential_tester import CredentialTester
    from menuscript.storage.credentials import CredentialsManager
    from menuscript.storage.hosts import HostManager
    from menuscript.storage.engagements import EngagementManager

    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("✗ No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("TEST CREDENTIALS")
    click.echo("=" * 70 + "\n")

    cm = CredentialsManager()
    hm = HostManager()

    # Get all credentials
    all_creds = cm.list_credentials(engagement_id)

    # Count by status
    untested = [c for c in all_creds if c.get('status') in ['untested', 'discovered'] and c.get('password')]
    valid = [c for c in all_creds if c.get('status') == 'valid']
    invalid = [c for c in all_creds if c.get('status') == 'invalid']

    click.echo(f"Credentials Summary:")
    click.echo(f"  • Total:     {len(all_creds)}")
    click.echo(f"  • Untested:  {len(untested)}")
    click.echo(f"  • Valid:     {len(valid)}")
    click.echo(f"  • Invalid:   {len(invalid)}")
    click.echo()

    if not untested:
        click.echo(click.style("No untested credentials found.", fg='yellow'))
        click.pause("\nPress any key to continue...")
        return

    # Menu options
    click.echo(click.style("TEST OPTIONS:", bold=True))
    click.echo("  [1] Test All Untested Credentials")
    click.echo("  [2] Test SSH Credentials Only")
    click.echo("  [3] Test SMB Credentials Only")
    click.echo("  [4] Test MySQL Credentials Only")
    click.echo("  [0] Back to Main Menu")
    click.echo()

    try:
        choice = click.prompt("Select option", type=int, default=0)

        if choice == 0:
            return

        service_filter = None
        if choice == 2:
            service_filter = 'ssh'
        elif choice == 3:
            service_filter = 'smb'
        elif choice == 4:
            service_filter = 'mysql'
        elif choice != 1:
            click.echo(click.style("Invalid selection!", fg='red'))
            click.pause()
            return

        # Build test list
        test_creds = []
        for cred in untested:
            if service_filter and cred.get('service', '').lower() != service_filter:
                continue

            host_id = cred.get('host_id')
            if not host_id:
                continue

            host_info = hm.get_host(host_id)
            if not host_info:
                continue

            cred_service = cred.get('service')
            cred_port = cred.get('port')

            if cred_service and cred_port:
                test_creds.append({
                    'credential_id': cred['id'],
                    'username': cred['username'],
                    'password': cred['password'],
                    'host': host_info['ip_address'],
                    'port': cred_port,
                    'service': cred_service
                })

        if not test_creds:
            click.echo(click.style(f"\nNo credentials found for {service_filter or 'testing'}.", fg='yellow'))
            click.pause("\nPress any key to continue...")
            return

        click.echo()
        click.echo(f"Found {len(test_creds)} credential(s) to test")
        click.echo()

        if not click.confirm("Proceed with testing?", default=True):
            return

        # Test credentials
        click.echo()
        tester = CredentialTester(timeout=5)
        valid_count = 0
        invalid_count = 0
        error_count = 0

        for idx, cred in enumerate(test_creds, 1):
            click.echo(f"[{idx}/{len(test_creds)}] Testing {cred['username']} @ {cred['host']}:{cred['port']} ({cred['service']})")

            result = tester.test_credential(
                cred['host'],
                cred['port'],
                cred['service'],
                cred['username'],
                cred['password']
            )

            # Update database
            new_status = result['status']
            if new_status == 'valid':
                valid_count += 1
                cm.update_credential_status(cred['credential_id'], 'valid')
                click.echo(click.style(f"  ✓ Valid!", fg='green'))
            elif new_status == 'invalid':
                invalid_count += 1
                cm.update_credential_status(cred['credential_id'], 'invalid')
                click.echo(click.style(f"  ✗ Invalid", fg='red'))
            else:
                error_count += 1
                click.echo(click.style(f"  ⚠ {new_status}: {result.get('message', 'Unknown')}", fg='yellow'))

        # Summary
        click.echo()
        click.echo(click.style("=" * 50, fg='cyan'))
        click.echo(click.style("TESTING COMPLETE", bold=True))
        click.echo(click.style("=" * 50, fg='cyan'))
        click.echo(f"Tested:  {len(test_creds)}")
        click.echo(click.style(f"Valid:   {valid_count}", fg='green'))
        click.echo(click.style(f"Invalid: {invalid_count}", fg='red'))
        click.echo(click.style(f"Errors:  {error_count}", fg='yellow'))
        click.echo()
        click.pause("Press any key to continue...")

    except (KeyboardInterrupt, click.Abort):
        return
