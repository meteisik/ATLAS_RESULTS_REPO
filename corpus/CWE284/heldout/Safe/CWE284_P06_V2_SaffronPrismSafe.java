import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronPrismAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SAFFRON_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronPrismSafeSink()).applySaffronPrismDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronPrismSafeSink {
    public void applySaffronPrismDeletion(String data, boolean authorized) throws SQLException {
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        try {
            PreparedStatement saffronPrismDelete = saffronPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronPrismDelete.setString(1, data);
            if (authorized) {
                saffronPrismDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronPrismConnection.close();
        }
    }
}
