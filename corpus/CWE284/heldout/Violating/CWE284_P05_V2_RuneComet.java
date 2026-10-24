import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeCometAccountId;

    private boolean runeCometAuthorized;

    private void applyRuneCometDeletion() throws SQLException {
        String data = runeCometAccountId;
        boolean authorized = runeCometAuthorized;
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        try {
            PreparedStatement runeCometDelete = runeCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeCometDelete.setString(1, data);
            runeCometDelete.executeUpdate();
        } finally {
            runeCometConnection.close();
        }
    }

    public void deleteRuneCometAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        runeCometAccountId = data;
        runeCometAuthorized = isAuthorized(data);
        applyRuneCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
