import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VividGlintSafe {

    public void deleteVividGlintAccount() throws SQLException {
        String data;
        data = System.getenv("VIVID_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VividGlintSafeBase baseObject = new CWE284_P12_V1_VividGlintSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VividGlintSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VividGlintSafeRemover extends CWE284_P12_V1_VividGlintSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection vividGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividGlint");
        try {
            PreparedStatement vividGlintDelete = vividGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividGlintDelete.executeUpdate();
            }
        } finally {
            vividGlintConnection.close();
        }
    }
}
