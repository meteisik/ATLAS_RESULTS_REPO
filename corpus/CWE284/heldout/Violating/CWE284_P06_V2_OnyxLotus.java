import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxLotus {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteOnyxLotusAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxLotusSink()).applyOnyxLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxLotusSink {
    public void applyOnyxLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        try {
            PreparedStatement onyxLotusDelete = onyxLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLotusDelete.setString(1, data);
            onyxLotusDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxLotusConnection.close();
        }
    }
}
