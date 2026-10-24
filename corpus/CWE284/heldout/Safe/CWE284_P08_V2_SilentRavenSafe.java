import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SilentRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSilentRavenAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SilentRavenSafeSink()).applySilentRavenDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SilentRavenSafeSink {
    public void applySilentRavenDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        try {
            PreparedStatement silentRavenDelete = silentRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentRavenDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                silentRavenDelete.executeUpdate();
            }
        } finally {
            silentRavenConnection.close();
        }
    }
}
