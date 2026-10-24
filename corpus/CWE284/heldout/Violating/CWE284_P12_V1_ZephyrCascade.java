import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrCascade {

    public void deleteZephyrCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrCascadeBase baseObject = new CWE284_P12_V1_ZephyrCascadeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrCascadeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrCascadeRemover extends CWE284_P12_V1_ZephyrCascadeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        try {
            PreparedStatement zephyrCascadeDelete = zephyrCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCascadeDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrCascadeDelete.executeUpdate();
            }
        } finally {
            zephyrCascadeConnection.close();
        }
    }
}
