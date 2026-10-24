import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrPrismSafe {

    public void deleteZephyrPrismAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_PRISM_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrPrismSafeBase baseObject = new CWE284_P12_V1_ZephyrPrismSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrPrismSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrPrismSafeRemover extends CWE284_P12_V1_ZephyrPrismSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        try {
            PreparedStatement zephyrPrismDelete = zephyrPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrPrismDelete.executeUpdate();
            }
        } finally {
            zephyrPrismConnection.close();
        }
    }
}
