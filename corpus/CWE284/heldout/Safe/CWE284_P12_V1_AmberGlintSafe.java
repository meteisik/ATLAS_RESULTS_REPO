import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberGlintSafe {

    public void deleteAmberGlintAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberGlintSafeBase baseObject = new CWE284_P12_V1_AmberGlintSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberGlintSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberGlintSafeRemover extends CWE284_P12_V1_AmberGlintSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        try {
            PreparedStatement amberGlintDelete = amberGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberGlintDelete.executeUpdate();
            }
        } finally {
            amberGlintConnection.close();
        }
    }
}
