import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetGlint {

    public void deleteVelvetGlintAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("VELVET_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetGlintChecker()).isAuthorized(requester);
        Connection velvetGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetGlint");
        try {
            PreparedStatement velvetGlintDelete = velvetGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetGlintDelete.setString(1, data);
            if (authorized) {
                velvetGlintDelete.executeUpdate();
            }
        } finally {
            velvetGlintConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetGlintChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
