const ldap = require('ldapjs');

class LdapConnection {
	constructor(url, bindDN, username, password) {
		this.bindDN = bindDN;
		this.opts = {
			url: url,
			bindDN: this.bindDN,
		};
		this.bind_opts = {
			username: username,
			password: password
		};
	}

	search(opts, callback) {
		let client = ldap.createClient(this.opts);
		client.bind(this.bind_opts.username, this.bind_opts.password, err => {
			if (err) {
				console.error(err);
				return;
			}

			let response = [];
			client.search(opts.baseDN, opts, (err, res) => {
				if (err) {
					console.error(err);
					return;
				}

				res.on('searchEntry', (entry) => {
					response.push(entry.object)
				});

				res.on('error', (err) => {
					console.error(err);
				});

				res.on('end', (result) => {
					client.unbind();
					callback(err, response);
				});
			});
		});
	}

	add(dn, attrs, callback) {
		let client = ldap.createClient(this.opts);
		client.bind(this.bind_opts.username, this.bind_opts.password, err => {
			if (err) {
				client.unbind();
				console.error(err);
				callback(err);
				return;
			}

			client.add(dn, attrs, err => {
				client.unbind();
				callback(err);
			});
		});
	}

	del(dn, callback) {
		let client = ldap.createClient(this.opts);
		client.bind(this.bind_opts.username, this.bind_opts.password, err => {
			if (err) {
				client.unbind();
				callback(err);
				return;
			}

			client.del(dn, err => {
				client.unbind();
				callback(err);
			});
		});
	}

	well_known_container(container, callback) {
		var wkguiduc = null;
		if (container == 'system') {
			wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD';
		} else if (container == 'computers') {
			wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD';
		} else if (container == 'dcs') {
			wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A';
		} else if (container == 'users') {
			wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD';
		}
		var opts = {
			baseDN: this.bindDN,
			scope: 'base',
			filter: '(objectClass=domain)',
			attributes: ['wellKnownObjects']
		};
		this.search(opts, (err, response) => {
			if (err) {
				console.log('ERROR: ' + JSON.stringify(err));
				callback(null);
				return;
			}
			let wkguids = response[0].wellKnownObjects;
			for (let wkguid of wkguids) {
				let swkguid = wkguid.split(':');
				if (swkguid[2] == wkguiduc) {
					callback(swkguid[swkguid.length-1]);
					return;
				}
			}
			callback(null);
		});
	}

	containers(callback, container=null) {
		if (container == null) {
			container = this.bindDN;
		}
		var opts = {
			baseDN: container,
			scope: 'one',
			filter: '(&(|(objectClass=organizationalUnit)(objectCategory=Container)(objectClass=builtinDomain))(!(|(cn=System)(cn=Program Data))))',
			attributes: ['name', 'distinguishedName']
		};
		this.search(opts, callback);
	}

	obj(dn, callback, attrs=null) {
		var opts = {
			baseDN: dn,
			scope: 'base',
			filter: '(objectClass=*)'
		};
		if (attrs != null) {
			opts.attributes = attrs;
		}

		this.search(opts, callback);
	}

	objects_list(container, callback, attrs=null) {
		var opts = {
			baseDN: container,
			scope: 'one',
			filter: '(|(&(|(objectClass=organizationalUnit)(objectCategory=Container)(objectClass=builtinDomain))(!(|(cn=System)(cn=Program Data))))(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectCategory=MSMQ-Custom-Recipient)(objectClass=printQueue)(objectCategory=Volume))'
		};
		if (attrs != null) {
			opts.attributes = attrs;
		}
		this.search(opts, callback);
	}

	add_contact(attrs, callback, container=null) {
		if (!('cn' in attrs)) {
			callback('CN was not provided');
			return;
		}
		attrs["objectClass"] = ["top", "person", "organizationalPerson", "contact"];
		attrs["objectCategory"] = 'CN=Person,CN=Schema,CN=Configuration,' + this.bindDN;
		if (!('name' in attrs)) {
			attrs["name"] = attrs["cn"];
		}

		if (container != null) {
			let dn = `CN=${attrs["cn"]},${container}`;
			attrs["distinguishedName"] = dn;
			this.add(dn, attrs, callback);
		} else {
			this.well_known_container('users', wkc => {
				let dn = `CN=${attrs["cn"]},${wkc}`;
				attrs["distinguishedName"] = dn;
				this.add(dn, attrs, callback);
			});
		}
	}
}
