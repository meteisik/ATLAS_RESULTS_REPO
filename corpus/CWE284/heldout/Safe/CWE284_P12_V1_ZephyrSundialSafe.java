import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrSundialSafe {

    public void deleteZephyrSundialAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrSundialSafeBase baseObject = new CWE284_P12_V1_ZephyrSundialSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrSundialSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrSundialSafeRemover extends CWE284_P12_V1_ZephyrSundialSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSundial");
        try {
            PreparedStatement zephyrSundialDelete = zephyrSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrSundialDelete.executeUpdate();
            }
        } finally {
            zephyrSundialConnection.close();
        }
    }
}
