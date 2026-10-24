import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrQuartz {

    public void deleteZephyrQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrQuartzBase baseObject = new CWE284_P12_V1_ZephyrQuartzRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrQuartzBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrQuartzRemover extends CWE284_P12_V1_ZephyrQuartzBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        try {
            PreparedStatement zephyrQuartzDelete = zephyrQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrQuartzDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrQuartzDelete.executeUpdate();
            }
        } finally {
            zephyrQuartzConnection.close();
        }
    }
}
