import path from "node:path";
import fs from "node:fs";
import url from "node:url";
const __dirname = url.fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
import { Controller, ControllerState } from "@lionrockjs/mvc";
import { Central, ORM, ControllerMixinDatabase, Model } from '@lionrockjs/central';
import ModelIdentifierPassword from "../dist/model/IdentifierPassword.mjs";

import { ControllerMixinAuth, ControllerRegister, ControllerAuth, ControllerAccount, ModelRole, ModelUser } from '@lionrockjs/mod-auth';
import * as ModAuthModule from '@lionrockjs/mod-auth';
import { DatabaseAdapterBunSqlite, ORMAdapterSQLite } from '@lionrockjs/adapter-database-bun-sqlite';
import * as SessionModule from '@lionrockjs/mixin-session';

import IdentifierPassword from "../dist/identifier/Password.mjs";

import ControllerAccountPassword from "../dist/controller/AccountPassword.mjs";

Model.defaultAdapter = ORMAdapterSQLite;
ControllerMixinDatabase.defaultAdapter = DatabaseAdapterBunSqlite;

function resetSqliteFile(source: string, target: string) {
  [target, `${target}-wal`, `${target}-shm`].forEach(file => {
    if (fs.existsSync(file)) fs.unlinkSync(file);
  });
  fs.copyFileSync(source, target);
}

async function setupCentral() {
  await Central.addModules([SessionModule, ModAuthModule]);
  Central.addConfig(new Map([
    ['auth', {
      databasePath: `${__dirname}/mockapp/db`,
      userDatabase: 'admin.sqlite',
      databaseMapName: 'admin',
      salt: 'thisislonglonglonglongtextover32bytes',
      destination: '/account',
      requireActivate: false,
      rootRole: 'root',
      databaseMap: new Map([
        ['admin', `${__dirname}/mockapp/db/admin.sqlite`],
      ]),
      identifiers: [
        IdentifierPassword,
      ],
    }],
    ['register', {
      allowPostAssignRoleID: false,
      defaultRole: 'member',
    }],
  ]));

  Central.modelFiles.set('model/IdentifierPassword', ModelIdentifierPassword);
  Central.modelFiles.set('model/Role', ModelRole);
  Central.modelFiles.set('model/User', ModelUser);
}

describe('password auth', () => {
  const dbPath = path.normalize(`${__dirname}/mockapp/db/admin.sqlite`);
  resetSqliteFile(`${__dirname}/mockapp/defaultDB/admin.sqlite`, dbPath);

  const dbPath2 = path.normalize(`${__dirname}/mockapp/db/session.sqlite`);
  resetSqliteFile(`${__dirname}/mockapp/defaultDB/session.sqlite`, dbPath2);

  beforeEach(async () => {
    await setupCentral();
  });

  afterEach(async () => {

  });

  test('setup', async () =>{
    expect(Central.config.session.name).toBe('lionrock-session');
  })

  test('constructor', async () => {
    const c = new ControllerRegister({ headers: {}, body: '', cookies: {} });
    const r = await c.execute(null, true);
    if (r.status === 500)console.log(c.error);
    expect(r.status).toBe(200);
    expect(c.error).toBe(null);
    expect(c.state.get(ControllerState.FULL_ACTION_NAME)).toBe('action_index');
  });

  test('hash function', async()=>{
    const hash = await IdentifierPassword.hash(1, 'alice', 'hello');
    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
  })

  test('register', async () =>{
    const password = 'hello';
    const c = new ControllerRegister({ headers: {}, body: 'username=alice&password='+password, cookies: {} });
    await c.execute('register_post', true);
    expect(c.state.get(ControllerState.FULL_ACTION_NAME)).toBe('action_register_post');

    const user = c.state.get(ControllerMixinAuth.USER);
    expect(user.person.first_name).toBe('alice');

    const database = c.state.get(ControllerMixinDatabase.DATABASES).get('admin');
    const identifier = await ORM.readBy(ModelIdentifierPassword, 'name', ['alice'], {database});
    expect(identifier.name).toBe('alice');

    await expect(IdentifierPassword.loginFilter(identifier, {password}, c.state)).resolves.toEqual({});
  });

  test('register with first name', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'first_name=Alice+Lee&username=alice2&password=hello', cookies: {} });
    await c.execute('register_post', true);

    const user = c.state.get('user');
    expect(user.person.first_name).toBe('Alice Lee');

    const database = c.state.get(ControllerMixinDatabase.DATABASES).get('admin');
    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['alice2'], {database})
    expect(identifier.name).toBe('alice2');
    await expect(IdentifierPassword.loginFilter(identifier, {password: 'hello'}, c.state)).resolves.toEqual({});
  });

  test('register duplicate username', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=bob&password=hello', cookies: {} });
    const res = await c.execute('register_post', true);
    if (res.status === 500)console.error(c.error);
    expect(res.status).toBe(302);
    const database = c.state.get(ControllerMixinDatabase.DATABASES).get('admin');
    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['bob'], {database})
    expect(identifier.name).toBe('bob');

    const c2 = new ControllerRegister({ headers: {}, body: 'username=bob&password=hello', cookies: {} });
    const res2 = await c2.execute('register_post', true);
    expect(res2.status).toBe(500);
    expect(c2.error.message).toBe("User Name bob already registered.");
  });

  test('register with retype password', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=bob2&password=hello&retype-password=hello', cookies: {} });
    await c.execute('register_post', true);

  });

  test('register retype password mismatch', async () =>{
    const c = new ControllerRegister({ headers: {}, body: 'username=bob3&password=hello&retype-password=helo', cookies: {} });
    const res = await c.execute('register_post', true);
    expect(res.status).toBe(500);
    expect(c.error.message).toBe("Retype password mismatch");
  });

  test('login', async ()=>{
    const c = new ControllerRegister({ headers: {}, body: 'username=charlie&password=wow', cookies: {} });
    const res = await c.execute('register_post', true);
    expect(res.status).toBe(302);
    const database = c.state.get(ControllerMixinDatabase.DATABASES).get('admin');
    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['charlie'], {database})

    const c2 = new ControllerAuth({ headers: {}, body: 'username=charlie&password=wow', cookies: {} });
    const res2 = await c2.execute('login_post', true);
    const request = c2.state.get(ControllerState.REQUEST);
    expect(request.session.logged_in).toBe(true);
    expect(request.session.user_id).toBe(identifier.user_id);
  })

  test('Login Fail', async ()=>{
    const c = new ControllerRegister({ headers: {}, body: 'username=charlie2&password=wow', cookies: {} });
    const res = await c.execute('register_post', true);
    expect(res.status).toBe(302);

    const c2 = new ControllerAuth({ headers: {}, body: 'username=charlie2&password=boom', cookies: {} });
    const res2 = await c2.execute('login_post', true);
    expect(res2.status).toBe(500);
    expect(c2.error.message).toBe("Password Mismatch");
  })

  test('Login Fail - no user name', async ()=>{
    const c = new ControllerAuth({ headers: {}, body: 'username=charlie99&password=boom', cookies: {} });
    const res = await c.execute('login_post', true);
    expect(res.status).toBe(500);
    expect(c.error.message).toBe("Identifier not found");
  })

  test('Logout', async () => {
    const c = new ControllerRegister({ headers: {}, body: 'username=lucky&password=hello', cookies: {} });
    const res = await c.execute('register_post', true);
    expect(res.status).toBe(302);

    const c2 = new ControllerAuth( {headers: {}, cookies: {}} );
    const res2 = await c2.execute('logout', true);
    expect(res2.status).toBe(200);
    const session = c2.state.get(ControllerState.REQUEST).session;
    expect(session.logged_in).toBe(false);
    expect(session.user_id).toBe(null);
  })

  test('change password without login', async ()=>{
    const c = new ControllerAccountPassword({raw:{url:'test'}, headers: {}, body: '', cookies: {}, session: {} });
    const res = await c.execute(null, true);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login?cp=test');
  })

  test('change password', async ()=>{
    const c = new ControllerRegister({ headers: {}, body: 'username=eve&password=hello', cookies: {} });
    await c.execute('register_post', true);

    const c2 = new ControllerAuth( {headers: {}, cookies: {}} );
    await c2.execute('logout', true);

    const c3 = new ControllerAuth({ headers: {}, body: 'username=eve&password=hello', cookies: {} });
    await c3.execute('login_post', true);

    const c4 = new ControllerAccount({ headers: {}, cookies: {}, session: c3.state.get(ControllerState.REQUEST).session })
    await c4.execute(null, true);
    const session = c4.state.get(ControllerState.REQUEST).session;

    const c5a = new ControllerAccount({ headers: {}, cookies: {}, session })
    await c5a.execute(null, true);

    const c5 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=somesome', cookies: {}, session });
    const res5 = await c5.execute('change_password_post', true);
    expect(res5.status).toBe(302);
    expect(res5.headers.location).toBe('/account/password/changed');


    const database = c.state.get(ControllerMixinDatabase.DATABASES).get('admin');
    const identifier = await ORM.readBy(IdentifierPassword.Model, 'name', ['eve'], {database})
    await expect(IdentifierPassword.loginFilter(identifier, {password: 'somesome'}, c.state)).resolves.toEqual({});

    //retype password match
    const c6 = new ControllerAccountPassword({ headers: {}, body: 'old-password=somesome&new-password=hello&retype-password=hello', cookies: {}, session });
    const res6 = await c6.execute('change_password_post', true);
    expect(res6.headers.location).toBe('/account/password/changed');
    expect(res6.status).toBe(302);

    //retype password not match
    const c7 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=somesome&retype-password=some', cookies: {}, session });
    const res7 = await c7.execute('change_password_post', true);
    expect(res7.status).toBe(500);
    expect(c7.error.message).toBe('Retype password mismatch');

    //identifier not found
    const c8 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=somesome', cookies: {}, session : {...session, user_id: 8756} });
    const res8 = await c8.execute('change_password_post', true);
    expect(res8.status).toBe(500);
    expect(c8.error.message).toBe('No Password Identifier associate to this user.');

    //old password mismatch
    const c9 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hehe&new-password=somesome', cookies: {}, session });
    const res9 = await c9.execute('change_password_post', true);
    expect(res9.status).toBe(500);
    expect(c9.error.message).toBe('Old Password Mismatch');

    //new password same as old password
    const c9b = new ControllerAccountPassword({ headers: {}, body: 'old-password=hello&new-password=hello', cookies: {}, session });
    const res9b = await c9b.execute('change_password_post', true);
    expect(res9b.status).toBe(500);
    expect(c9b.error.message).toBe('New password is same as old password');

    //password change done
    const c10 = new ControllerAccountPassword({ headers: {}, body: 'old-password=hehe&new-password=somesome', cookies: {}, session });
    await c10.execute('change_password_done', true);
    expect(c10.state.get(ControllerState.REQUEST).session.logged_in).toBe(false);
  });

});
