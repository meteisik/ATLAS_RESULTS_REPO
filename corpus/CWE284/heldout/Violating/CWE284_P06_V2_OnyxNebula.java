import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteOnyxNebulaAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxNebulaSink()).applyOnyxNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxNebulaSink {
    public void applyOnyxNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        try {
            PreparedStatement onyxNebulaDelete = onyxNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxNebulaDelete.setString(1, data);
            onyxNebulaDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxNebulaConnection.close();
        }
    }
}
