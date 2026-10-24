import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronGlintSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronGlintAccount() throws SQLException {
        data = System.getenv("SAFFRON_GLINT_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronGlintSafeSink()).applySaffronGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronGlintSafeSink {
    public void applySaffronGlintDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronGlintSafe.data;
        boolean authorized = CWE284_P10_V1_SaffronGlintSafe.authorized;
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        try {
            PreparedStatement saffronGlintDelete = saffronGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronGlintDelete.setString(1, data);
            if (authorized) {
                saffronGlintDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronGlintConnection.close();
        }
    }
}
