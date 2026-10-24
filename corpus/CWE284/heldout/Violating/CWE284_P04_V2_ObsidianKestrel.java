import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianKestrel {
    private static boolean privateReturnsTrue() { return true; }

    private boolean checkObsidianKestrelAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianKestrelAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianKestrelAccess(data);
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        try {
            PreparedStatement obsidianKestrelDelete = obsidianKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianKestrelDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianKestrelDelete.executeUpdate();
            }
        } finally {
            obsidianKestrelConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
