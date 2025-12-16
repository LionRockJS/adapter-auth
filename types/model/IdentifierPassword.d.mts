import { Model } from '@lionrockjs/central';
export default class IdentifierPassword extends Model {
    user_id: string | null;
    name: string | null;
    hash: string | null;
    static joinTablePrefix: string;
    static tableName: string;
    static fields: Map<string, string>;
    static belongsTo: Map<string, string>;
}
