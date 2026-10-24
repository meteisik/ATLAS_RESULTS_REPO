import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetGlintSafe {
    private static int privateFive = 5;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetGlintAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("VELVET_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetGlintSafeSink()).applyVelvetGlintDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetGlintSafeSink {
    public void applyVelvetGlintDeletion(CWE284_P09_V2_VelvetGlintSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
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
