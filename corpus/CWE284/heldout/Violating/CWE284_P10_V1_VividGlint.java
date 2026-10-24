import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VividGlint {

    public static String data;

    public static boolean authorized;

    public void deleteVividGlintAccount() throws SQLException {
        data = System.getenv("VIVID_GLINT_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VividGlintSink()).applyVividGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VividGlintSink {
    public void applyVividGlintDeletion() throws SQLException {
        String data = CWE284_P10_V1_VividGlint.data;
        boolean authorized = CWE284_P10_V1_VividGlint.authorized;
        Connection vividGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividGlint");
        try {
            PreparedStatement vividGlintDelete = vividGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividGlintDelete.setString(1, data);
            vividGlintDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            vividGlintConnection.close();
        }
    }
}
