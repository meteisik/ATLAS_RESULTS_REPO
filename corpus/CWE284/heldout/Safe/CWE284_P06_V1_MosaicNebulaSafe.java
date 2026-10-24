import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicNebulaSafe {

    public void deleteMosaicNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_NEBULA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicNebulaSafeSink()).applyMosaicNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicNebulaSafeSink {
    public void applyMosaicNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
        try {
            PreparedStatement mosaicNebulaDelete = mosaicNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicNebulaDelete.setString(1, data);
            if (authorized) {
                mosaicNebulaDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicNebulaConnection.close();
        }
    }
}
