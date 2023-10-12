const { KohanaJS_Jest, KohanaJS, ORM } = require('kohanajs-jest');
const results = KohanaJS_Jest.init({
  DIR: __dirname,
  CONFIGS: ['auth', 'register'],
  PRELOAD: [['model/IdentifierPassword.js', require('../classes/model/IdentifierPassword')]],
  DATABASES: ['admin.sqlite', 'session.sqlite'],
});
const db = results[0];

//classes to test
const { ControllerRegister, ControllerAuth, ControllerAccount } = require('@kohanajs/mod-auth');
const IdentifierPassword = require('../classes/identifier/Password');
const ControllerAccountPassword = require('../classes/controller/AccountPassword');

describe('password auth', () => {
  test('KohanaJS setup', async () =>{
    expect(KohanaJS.config.session.name).toBe('kohanajs-session');
  })

  test('constructor', async () => {
    const c = new ControllerRegister({ headers: {}, body: '', cookies: {} });
    const r = await c.execute();
    if (r.status === 500)console.log(c.error);
    expect(r.status).toBe(200);
    expect(c.error).toBe(null);
    expect(c.state.get('full_action_name')).toBe('action_index');
  });

  test('register', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=alice&password=hello', cookies: {} });
    await c.execute('register_post');
    expect(c.state.get('full_action_name')).toBe('action_register_post');

    const user = c.state.get('user');
    expect(user.person.first_name).toBe('alice');

    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['alice'], {database: db})
    expect(identifier.name).toBe('alice');
    expect(identifier.hash).toBe(IdentifierPassword.hash(user.id, 'alice', 'hello'));
  });

  test('register with first name', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'first_name=Alice+Lee&username=alice2&password=hello', cookies: {} });
    await c.execute('register_post');

    const user = c.state.get('user');
    expect(user.person.first_name).toBe('Alice Lee');

    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['alice2'], {database: db})
    expect(identifier.name).toBe('alice2');
    expect(identifier.hash).toBe(IdentifierPassword.hash(user.id, 'alice2', 'hello'));
  });

  test('register duplicate username', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=bob&password=hello', cookies: {} });
    await c.execute('register_post');
    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['bob'], {database: db})
    expect(identifier.name).toBe('bob');

    const c2 = new ControllerRegister({ headers: {}, body: 'username=bob&password=hello', cookies: {} });
    await c2.execute('register_post');
    expect(c2.status).toBe(500);
    expect(c2.error.message).toBe("User Name bob already in use.");
  });

  test('register with retype password', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=bob2&password=hello&retype-password=hello', cookies: {} });
    await c.execute('register_post');

  });

  test('register retype password mismatch', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=bob3&password=hello&retype-password=helo', cookies: {} });
    await c.execute('register_post');
    expect(c.status).toBe(500);
    expect(c.error.message).toBe("Retype password mismatch");
  });

  test('login', async ()=>{
    const c = new ControllerRegister({ headers: {}, body: 'username=charlie&password=wow', cookies: {} });
    await c.execute('register_post');
    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['charlie'], {database: db})

    const c2 = new ControllerAuth({ headers: {}, body: 'username=charlie&password=wow', cookies: {} });
    await c2.execute('login_post');
    expect(c2.request.session.logged_in).toBe(true);
    expect(c2.request.session.user_id).toBe(identifier.user_id);
  })

  test('Login Fail', async ()=>{
    const c = new ControllerRegister({ headers: {}, body: 'username=charlie2&password=wow', cookies: {} });
    await c.execute('register_post');

    const c2 = new ControllerAuth({ headers: {}, body: 'username=charlie2&password=boom', cookies: {} });
    await c2.execute('login_post');
    expect(c2.status).toBe(500);
    expect(c2.error.message).toBe("Password Mismatch");
  })

  test('Login Fail - no user name', async ()=>{
    const c = new ControllerAuth({ headers: {}, body: 'username=charlie99&password=boom', cookies: {} });
    await c.execute('login_post');
    expect(c.status).toBe(500);
    expect(c.error.message).toBe("Identifier not found");
  })

  test('Logout', async () => {
    const c = new ControllerRegister({ headers: {}, body: 'username=lucky&password=hello', cookies: {} });
    await c.execute('register_post');
    const c2 = new ControllerAuth( {headers: {}, cookies: {}} );
    await c2.execute('logout');
    const session = c2.request.session;
    expect(session.logged_in).toBe(false);
    expect(session.user_id).toBe(null);
  })

  test('change password without login', async ()=>{
    const c = new ControllerAccountPassword({raw:{url:'test'}, headers: {}, body: '', cookies: {}, session: {} });
    await c.execute();
    expect(c.status).toBe(302);
    expect(c.headers.location).toBe('/login?cp=test');
  })

  test('change password', async ()=>{
    const c = new ControllerRegister({ headers: {}, body: 'username=eve&password=hello', cookies: {} });
    await c.execute('register_post');

    const c2 = new ControllerAuth( {headers: {}, cookies: {}} );
    await c2.execute('logout');

    const c3 = new ControllerAuth({ headers: {}, body: 'username=eve&password=hello', cookies: {} });
    await c3.execute('login_post');

    const c4 = new ControllerAccount({ headers: {}, cookies: {}, session: c3.request.session })
    await c4.execute();
    const session = c4.request.session;

    const c5a = new ControllerAccount({ headers: {}, cookies: {}, session })
    await c5a.execute();

    const c5 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=somesome', cookies: {}, session });
    await c5.execute('change_password_post');
    expect(c5.headers.location).toBe('/account/password/changed');
    expect(c5.status).toBe(302);

    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['eve'], {database: db})
    expect(IdentifierPassword.hash(identifier.user_id, 'eve', 'somesome')).toBe(identifier.hash);

    //retype password match
    const c6 = new ControllerAccountPassword({ headers: {}, body: 'old-password=somesome&new-password=hello&retype-password=hello', cookies: {}, session });
    await c6.execute('change_password_post');
    expect(c6.headers.location).toBe('/account/password/changed');
    expect(c6.status).toBe(302);

    //retype password not match
    const c7 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=somesome&retype-password=some', cookies: {}, session });
    await c7.execute('change_password_post');
    expect(c7.status).toBe(500);
    expect(c7.error.message).toBe('Retype password mismatch');

    //identifier not found
    const c8 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=somesome', cookies: {}, session : {...session, user_id: 8756} });
    await c8.execute('change_password_post');
    expect(c8.status).toBe(500);
    expect(c8.error.message).toBe('No Password Identifier associate to this user.');

    //old password mismatch
    const c9 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hehe&new-password=somesome', cookies: {}, session });
    await c9.execute('change_password_post');
    expect(c9.status).toBe(500);
    expect(c9.error.message).toBe('Old Password Mismatch');

    //new password same as old password
    const c9b = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=hello', cookies: {}, session });
    await c9b.execute('change_password_post');
    expect(c9b.status).toBe(500);
    expect(c9b.error.message).toBe('New password is same as old password');

    //password change done
    const c10 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hehe&new-password=somesome', cookies: {}, session });
    await c10.execute('change_password_done');

    expect(c10.request.session.logged_in).toBe(false);
  });

});