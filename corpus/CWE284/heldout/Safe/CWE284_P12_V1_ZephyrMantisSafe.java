import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrMantisSafe {

    public void deleteZephyrMantisAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrMantisSafeBase baseObject = new CWE284_P12_V1_ZephyrMantisSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrMantisSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrMantisSafeRemover extends CWE284_P12_V1_ZephyrMantisSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        try {
            PreparedStatement zephyrMantisDelete = zephyrMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrMantisDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrMantisDelete.executeUpdate();
            }
        } finally {
            zephyrMantisConnection.close();
        }
    }
}
