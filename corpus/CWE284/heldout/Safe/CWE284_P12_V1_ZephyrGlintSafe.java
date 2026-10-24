import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrGlintSafe {

    public void deleteZephyrGlintAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrGlintSafeBase baseObject = new CWE284_P12_V1_ZephyrGlintSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrGlintSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrGlintSafeRemover extends CWE284_P12_V1_ZephyrGlintSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        try {
            PreparedStatement zephyrGlintDelete = zephyrGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrGlintDelete.executeUpdate();
            }
        } finally {
            zephyrGlintConnection.close();
        }
    }
}
