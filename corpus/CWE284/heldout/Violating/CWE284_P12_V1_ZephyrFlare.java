import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrFlare {

    public void deleteZephyrFlareAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrFlareBase baseObject = new CWE284_P12_V1_ZephyrFlareRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrFlareBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrFlareRemover extends CWE284_P12_V1_ZephyrFlareBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        try {
            PreparedStatement zephyrFlareDelete = zephyrFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrFlareDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrFlareDelete.executeUpdate();
            }
        } finally {
            zephyrFlareConnection.close();
        }
    }
}
