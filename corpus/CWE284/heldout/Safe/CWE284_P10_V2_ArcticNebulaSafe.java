import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticNebulaSafe {

    public static String data;

    public static boolean authorized;

    public void deleteArcticNebulaAccount() throws SQLException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_NEBULA_ACCOUNT_ID");
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticNebulaSafeSink()).applyArcticNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticNebulaSafeSink {
    public void applyArcticNebulaDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticNebulaSafe.data;
        boolean authorized = CWE284_P10_V2_ArcticNebulaSafe.authorized;
        Connection arcticNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticNebula");
        try {
            PreparedStatement arcticNebulaDelete = arcticNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticNebulaDelete.setString(1, data);
            if (authorized) {
                arcticNebulaDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticNebulaConnection.close();
        }
    }
}
