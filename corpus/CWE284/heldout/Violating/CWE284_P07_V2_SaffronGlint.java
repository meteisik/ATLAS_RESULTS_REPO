import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronGlintAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SAFFRON_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronGlintChecker()).isAuthorized(requester);
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        try {
            PreparedStatement saffronGlintDelete = saffronGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronGlintDelete.setString(1, data);
            if (authorized) {
                saffronGlintDelete.executeUpdate();
            }
        } finally {
            saffronGlintConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronGlintChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
