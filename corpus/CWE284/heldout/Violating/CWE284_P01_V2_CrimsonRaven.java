import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_CrimsonRaven {
    private static int privateFive = 5;

    public void deleteCrimsonRavenAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("CRIMSON_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection crimsonRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonRaven");
        try {
            PreparedStatement crimsonRavenDelete = crimsonRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonRavenDelete.setString(1, data);
            crimsonRavenDelete.executeUpdate();
        } finally {
            crimsonRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
