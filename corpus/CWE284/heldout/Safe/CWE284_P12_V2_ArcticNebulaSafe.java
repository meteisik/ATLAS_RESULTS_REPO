import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_ArcticNebulaSafe {
    private static boolean privateTrue = true;

    public void deleteArcticNebulaAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ARCTIC_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_ArcticNebulaSafeBase baseObject = new CWE284_P12_V2_ArcticNebulaSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_ArcticNebulaSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_ArcticNebulaSafeRemover extends CWE284_P12_V2_ArcticNebulaSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticNebula");
        try {
            PreparedStatement arcticNebulaDelete = arcticNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticNebulaDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticNebulaDelete.executeUpdate();
            }
        } finally {
            arcticNebulaConnection.close();
        }
    }
}
