import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberGlintSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public static boolean authorized;

    public void deleteAmberGlintAccount() throws SQLException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberGlintSafeSink()).applyAmberGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberGlintSafeSink {
    public void applyAmberGlintDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberGlintSafe.data;
        boolean authorized = CWE284_P10_V2_AmberGlintSafe.authorized;
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        try {
            PreparedStatement amberGlintDelete = amberGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberGlintDelete.setString(1, data);
            if (authorized) {
                amberGlintDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberGlintConnection.close();
        }
    }
}
