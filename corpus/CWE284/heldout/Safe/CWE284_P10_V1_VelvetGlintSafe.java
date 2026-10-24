import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetGlintSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetGlintAccount() throws SQLException {
        data = System.getenv("VELVET_GLINT_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetGlintSafeSink()).applyVelvetGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetGlintSafeSink {
    public void applyVelvetGlintDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetGlintSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetGlintSafe.authorized;
        Connection velvetGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetGlint");
        try {
            PreparedStatement velvetGlintDelete = velvetGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetGlintDelete.setString(1, data);
            if (authorized) {
                velvetGlintDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetGlintConnection.close();
        }
    }
}
