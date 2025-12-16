import { ControllerMixin, ControllerState } from '@lionrockjs/mvc';
import { ORM, ControllerMixinDatabase } from '@lionrockjs/central';
import { ControllerMixinMultipartForm } from '@lionrockjs/mixin-form';
import { HelperAuth, ControllerMixinAuth } from '@lionrockjs/mod-auth';
import IdentifierPassword from '../identifier/Password.mjs';
export default class ControllerMixinAccountPassword extends ControllerMixin {
    static USER = 'accountUser';
    static DATABASE_NAME = ControllerMixinAuth.DATABASE_NAME;
    static IDENTIFIER_DATABASE_NAME = ControllerMixinAuth.IDENTIFIER_DATABASE_NAME;
    static IDENTIFIER = 'accountPasswordIdentifier';
    static init(state) {
        if (!state.get(this.DATABASE_NAME))
            state.set(this.DATABASE_NAME, 'admin');
        if (!state.get(this.IDENTIFIER_DATABASE_NAME))
            state.set(this.IDENTIFIER_DATABASE_NAME, 'admin');
        if (!state.get(this.IDENTIFIER))
            state.set(this.IDENTIFIER, IdentifierPassword);
    }
    static async action_change_password_post(state) {
        const $_POST = state.get(ControllerMixinMultipartForm.POST_DATA);
        const { "old-password": oldPassword, "new-password": newPassword, "retype-password": retypePassword } = $_POST;
        //check retype password matches
        const Identifier = state.get(this.IDENTIFIER);
        Identifier.matchRetypePassword(newPassword, retypePassword);
        if (newPassword === oldPassword)
            throw new Error('New password is same as old password');
        const database = state.get(ControllerMixinDatabase.DATABASES).get(state.get(this.IDENTIFIER_DATABASE_NAME));
        const { user_id } = state.get(ControllerState.REQUEST).session;
        const identifierInstances = await ORM.readBy(Identifier.Model, 'user_id', [user_id], { database, asArray: true });
        //check identifier exist
        if (identifierInstances.length === 0) {
            throw new Error('No Password Identifier associate to this user.');
        }
        //verify old password hash;
        await Promise.all(identifierInstances.map(async (it) => {
            try {
                await Identifier.loginFilter(it, { password: oldPassword }, state);
            }
            catch (e) {
                throw new Error('Old Password Mismatch');
            }
        }));
        //update identifier record
        await Promise.all(identifierInstances.map(async (it) => {
            it.hash = await Identifier.hash(user_id, it.name, newPassword);
            await it.write();
        }));
        await HelperAuth.redirect(state, '/account/password/changed');
    }
    static async action_change_password_done(state) {
        await ControllerMixinAuth.action_logout(state);
    }
}
