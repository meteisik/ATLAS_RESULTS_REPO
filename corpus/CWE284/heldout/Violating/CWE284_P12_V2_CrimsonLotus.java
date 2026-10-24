import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonLotus {

    public void deleteCrimsonLotusAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("CRIMSON_LOTUS_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonLotusBase baseObject = new CWE284_P12_V2_CrimsonLotusRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonLotusBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonLotusRemover extends CWE284_P12_V2_CrimsonLotusBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLotus");
        try {
            PreparedStatement crimsonLotusDelete = crimsonLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonLotusDelete.executeUpdate();
            }
        } finally {
            crimsonLotusConnection.close();
        }
    }
}
