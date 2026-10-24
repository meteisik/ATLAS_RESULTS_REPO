import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_IvoryOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteIvoryOrbitAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (IO.staticFive == 5) {
                data = System.getenv("IVORY_ORBIT_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection ivoryOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryOrbit");
            try {
                PreparedStatement ivoryOrbitDelete = ivoryOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                ivoryOrbitDelete.setString(1, data);
                ivoryOrbitDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                ivoryOrbitConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
