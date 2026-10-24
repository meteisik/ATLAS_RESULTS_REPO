import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronCascadeAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("SAFFRON_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronCascadeChecker()).isAuthorized(requester);
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        try {
            PreparedStatement saffronCascadeDelete = saffronCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCascadeDelete.setString(1, data);
            if (authorized) {
                saffronCascadeDelete.executeUpdate();
            }
        } finally {
            saffronCascadeConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronCascadeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
