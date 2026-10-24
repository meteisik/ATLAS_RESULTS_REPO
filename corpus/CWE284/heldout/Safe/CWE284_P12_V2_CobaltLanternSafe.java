import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CobaltLanternSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteCobaltLanternAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CobaltLanternSafeBase baseObject = new CWE284_P12_V2_CobaltLanternSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CobaltLanternSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CobaltLanternSafeRemover extends CWE284_P12_V2_CobaltLanternSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection cobaltLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLantern");
        try {
            PreparedStatement cobaltLanternDelete = cobaltLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                cobaltLanternDelete.executeUpdate();
            }
        } finally {
            cobaltLanternConnection.close();
        }
    }
}
