import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private boolean checkObsidianNebulaAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianNebulaAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("OBSIDIAN_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianNebulaAccess(data);
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        try {
            PreparedStatement obsidianNebulaDelete = obsidianNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianNebulaDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianNebulaDelete.executeUpdate();
            }
        } finally {
            obsidianNebulaConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
