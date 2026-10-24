import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianLotusAccountId;

    private boolean obsidianLotusAuthorized;

    private void applyObsidianLotusDeletion() throws SQLException {
        String data = obsidianLotusAccountId;
        boolean authorized = obsidianLotusAuthorized;
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        try {
            PreparedStatement obsidianLotusDelete = obsidianLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLotusDelete.setString(1, data);
            if (authorized) {
                obsidianLotusDelete.executeUpdate();
            }
        } finally {
            obsidianLotusConnection.close();
        }
    }

    public void deleteObsidianLotusAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianLotusAccountId = data;
        obsidianLotusAuthorized = isAuthorized(data);
        applyObsidianLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
