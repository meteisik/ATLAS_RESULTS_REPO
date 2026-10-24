import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SilentLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSilentLanternAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SilentLanternSafeSink()).applySilentLanternDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SilentLanternSafeSink {
    public void applySilentLanternDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        try {
            PreparedStatement silentLanternDelete = silentLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                silentLanternDelete.executeUpdate();
            }
        } finally {
            silentLanternConnection.close();
        }
    }
}
