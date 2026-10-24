import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_LunarHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteLunarHelixAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (IO.staticReturnsTrue()) {
                data = System.getenv("LUNAR_HELIX_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection lunarHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarHelix");
            try {
                PreparedStatement lunarHelixDelete = lunarHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                lunarHelixDelete.setString(1, data);
                if (authorized) {
                    lunarHelixDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                lunarHelixConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
