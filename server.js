'use strict';

let db = {
	addUser: (username, struct) => {
		let userHandleToUsername = localStorage.getItem('userHandleToUsername');
		if (!userHandleToUsername) userHandleToUsername = '{}';

		userHandleToUsername = JSON.parse(userHandleToUsername);

		userHandleToUsername[struct.id] = username;

		localStorage.setItem(username, JSON.stringify(struct));
		localStorage.setItem(
			'userHandleToUsername',
			JSON.stringify(userHandleToUsername)
		);
	},
	getUser: (username) => {
		let userJSON = localStorage.getItem(username);
		if (!userJSON) throw new Error(`Username "${username}" does not exist!`);

		return JSON.parse(userJSON);
	},

	getUserByUserHandle: (userHandle) => {
		try {
			let userHandleToUsername = localStorage.getItem('userHandleToUsername');
			if (!userHandleToUsername) userHandleToUsername = '{}';

			userHandleToUsername = JSON.parse(userHandleToUsername);

			let username = userHandleToUsername[userHandle];

			let userJSON = localStorage.getItem(username);
			if (!userJSON) throw new Error(`Username "${username}" does not exist!`);

			return JSON.parse(userJSON);
		} catch (e) {
			return {};
		}
	},
	userExists: (username) => {
		let userJSON = localStorage.getItem(username);
		if (!userJSON) return false;

		return true;
	},
	updateUser: (username, struct) => {
		let userJSON = localStorage.getItem(username);
		if (!userJSON) throw new Error(`Username "${username}" does not exist!`);

		localStorage.setItem(username, JSON.stringify(struct));
	},
	deleteUser: (username) => {
		localStorage.removeItem(username);
	},
};

let session = {};

const registerPassword = (payload) => {
	session = {};
	if (payload.username === '' && payload.password === '')
		return Promise.reject({ status: 'fail', errorMessage: 'Invalid input!' });

	if (
		db.userExists(payload.username) &&
		db.getUser(payload.username).registrationComplete
	)
		return Promise.reject({
			status: 'failed',
			errorMessage: 'User already exists!',
		});

	db.deleteUser(payload.username);

	payload.id = base64url.encode(generateRandomBuffer(32));
	payload.credentials = [];

	db.addUser(payload.username, payload);

	session.username = payload.username;

	return Promise.resolve({ status: 'startFIDOEnrolment' });
};

const loginPassword = (payload) => {
	if (!db.userExists(payload.username))
		return Promise.reject('Wrong username or password!');

	let user = db.getUser(payload.username);
	if (user.password !== payload.password)
		return Promise.reject('Wrong username or password!');

	session.username = payload.username;

	return Promise.resolve({ status: 'startFIDOAuthentication' });
};

const getMakeCredentialChallenge = (options) => {
	console.log('Attestation option called');
	if (!session.username)
		return Promise.reject({ status: 'failed', errorMessage: 'Access denied!' });

	let user = db.getUser(session.username);
	session.challenge = base64url.encode(generateRandomBuffer(32));

	let attachmentType;
	if (
		window.navigator.userAgent.match(/Android/i) ||
		window.navigator.userAgent.match(/webOS/i) ||
		window.navigator.userAgent.match(/iPhone/i) ||
		window.navigator.userAgent.match(/iPad/i) ||
		window.navigator.userAgent.match(/iPod/i) ||
		window.navigator.userAgent.match(/BlackBerry/i) ||
		window.navigator.userAgent.match(/Windows Phone/i)
	) {
		attachmentType = 'platform';
	} else {
		attachmentType = 'cross-platform';
	}

	let publicKey = {
		challenge: session.challenge,

		rp: {
			name: 'Jio',
			id: 'yashzawar02.github.io',
		},

		user: {
			id: user.id,
			name: user.username,
			displayName: user.displayName,
		},

		pubKeyCredParams: [
			{ type: 'public-key', alg: -7 },
			{ type: 'public-key', alg: -257 },
		],

		authenticatorSelection: {
			authenticatorAttachment: attachmentType,
			requireResidentKey: true,
		},

		timeout: 60000,

		status: 'ok',
	};

	if (options) {
		if (options.attestation) publicKey.attestation = options.attestation;

		if (options.rpId) publicKey.rp.id = options.rpId;

		if (options.uv)
			publicKey.authenticatorSelection.userVerification = 'required';
	}

	if (session.rk) {
		if (!publicKey.authenticatorSelection)
			publicKey.authenticatorSelection = {};

		publicKey.authenticatorSelection.requireResidentKey = true;
	}

	return Promise.resolve(publicKey);
};

const makeCredentialResponse = (payload) => {
	if (!session.username)
		return Promise.reject({ status: 'failed', errorMessage: 'Access denied!' });

	let user = db.getUser(session.username);

	user.registrationComplete = true;
	user.credentials.push(payload.id);

	db.updateUser(session.username, user);

	session = {};

	return Promise.resolve({ status: 'ok' });
};

const getAssertionChallenge = () => {
	console.log('Assertion request');
	session.challenge = base64url.encode(generateRandomBuffer(32));

	let publicKey = {
		challenge: session.challenge,
		status: 'ok',
	};

	if (session.rk) {
		delete publicKey.allowCredentials;
	}

	if (session.uv) publicKey.userVerification = 'required';

	return Promise.resolve(publicKey);
};

const getAssertionResponse = (payload) => {
	if (
		!session.username &&
		!db.getUserByUserHandle(payload.response.userHandle)
	) {
		return Promise.reject({ status: 'fail', errorMessage: 'Access denied!' });
	}

	console.log('Assertion results');

	session = {};

	return Promise.resolve({ status: 'ok' });
};
