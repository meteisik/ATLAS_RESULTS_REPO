import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private boolean checkObsidianOrbitAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianOrbitAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianOrbitAccess(data);
        Connection obsidianOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianOrbit");
        try {
            PreparedStatement obsidianOrbitDelete = obsidianOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianOrbitDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianOrbitDelete.executeUpdate();
            }
        } finally {
            obsidianOrbitConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
