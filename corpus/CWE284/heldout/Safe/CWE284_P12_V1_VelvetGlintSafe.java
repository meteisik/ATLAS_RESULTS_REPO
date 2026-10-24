import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetGlintSafe {

    public void deleteVelvetGlintAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetGlintSafeBase baseObject = new CWE284_P12_V1_VelvetGlintSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetGlintSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetGlintSafeRemover extends CWE284_P12_V1_VelvetGlintSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetGlint");
        try {
            PreparedStatement velvetGlintDelete = velvetGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetGlintDelete.executeUpdate();
            }
        } finally {
            velvetGlintConnection.close();
        }
    }
}
