import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetGlintSafe {
    private static boolean privateTrue = true;

    public void deleteVelvetGlintAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetGlintSafeSink()).applyVelvetGlintDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetGlintSafeSink {
    public void applyVelvetGlintDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
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
