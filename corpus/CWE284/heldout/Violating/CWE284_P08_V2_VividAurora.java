import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VividAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteVividAuroraAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("VIVID_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VividAuroraSink()).applyVividAuroraDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VividAuroraSink {
    public void applyVividAuroraDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        try {
            PreparedStatement vividAuroraDelete = vividAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividAuroraDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividAuroraDelete.executeUpdate();
            }
        } finally {
            vividAuroraConnection.close();
        }
    }
}
