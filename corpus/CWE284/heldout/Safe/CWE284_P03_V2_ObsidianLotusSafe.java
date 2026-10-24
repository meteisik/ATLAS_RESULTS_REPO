import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianLotusSafe {
    private static boolean privateReturnsTrue() { return true; }

    private void applyObsidianLotusDeletion(String data, boolean authorized) throws SQLException {
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
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyObsidianLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
