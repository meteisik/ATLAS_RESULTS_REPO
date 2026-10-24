import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_CrimsonNebula {
    private static boolean privateTrue = true;

    public void deleteCrimsonNebulaAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("CRIMSON_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
        try {
            PreparedStatement crimsonNebulaDelete = crimsonNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonNebulaDelete.setString(1, data);
            crimsonNebulaDelete.executeUpdate();
        } finally {
            crimsonNebulaConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
