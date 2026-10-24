import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronMantis {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronMantisAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SAFFRON_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronMantisSink()).applySaffronMantisDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronMantisSink {
    public void applySaffronMantisDeletion(String data, boolean authorized) throws SQLException {
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        try {
            PreparedStatement saffronMantisDelete = saffronMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronMantisDelete.setString(1, data);
            saffronMantisDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronMantisConnection.close();
        }
    }
}
