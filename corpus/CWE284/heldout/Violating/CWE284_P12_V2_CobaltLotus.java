import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CobaltLotus {
    private static boolean privateTrue = true;

    public void deleteCobaltLotusAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CobaltLotusBase baseObject = new CWE284_P12_V2_CobaltLotusRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CobaltLotusBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CobaltLotusRemover extends CWE284_P12_V2_CobaltLotusBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection cobaltLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLotus");
        try {
            PreparedStatement cobaltLotusDelete = cobaltLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                cobaltLotusDelete.executeUpdate();
            }
        } finally {
            cobaltLotusConnection.close();
        }
    }
}
