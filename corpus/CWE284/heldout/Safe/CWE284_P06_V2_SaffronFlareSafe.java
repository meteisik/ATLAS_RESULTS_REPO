import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronFlareAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("SAFFRON_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronFlareSafeSink()).applySaffronFlareDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronFlareSafeSink {
    public void applySaffronFlareDeletion(String data, boolean authorized) throws SQLException {
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        try {
            PreparedStatement saffronFlareDelete = saffronFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronFlareDelete.setString(1, data);
            if (authorized) {
                saffronFlareDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronFlareConnection.close();
        }
    }
}
